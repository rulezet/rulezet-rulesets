rule infected_09_10_18_phishing_smartsheet_index3 {
  meta:
    description = "account - file index3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-12"
    hash1       = "58479bd9dd37fb60a285ce31e5a2917181a59b4c76cd8ab689da25cefd64cb85"

  strings:
    $x1  = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0" fullword ascii
    $s2  = "<meta http-equiv=\"refresh\" content=\"5;url=https://onedrive.live.com/\" />" fullword ascii
    $s3  = "TenantBranding.AddBoilerPlateText(Constants.DEFAULT_BOILERPLATE_TEXT, Constants.DEFAULT_BOILERPLATE_HEADER);" fullword ascii
    $s4  = "<img src=\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/microsoft_logo.png\" id=\"IMG_12\" alt=''" ascii
    $s5  = "User.UpdateLogo(Constants.DEFAULT_LOGO, Constants.DEFAULT_LOGO_ALT);" fullword ascii
    $s6  = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
    $s7  = "Constants.DEFAULT_ILLUSTRATION = 'https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images/default_signin_ill" ascii
    $s8  = "User.UpdateBackground(Constants.DEFAULT_ILLUSTRATION, Constants.DEFAULT_BACKGROUND_COLOR);" fullword ascii
    $s9  = "User.UpdateLogo('', \"You signed out of your account\", true);" fullword ascii
    $s10 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0-sm" ascii
    $s11 = "background: rgba(0, 0, 0, 0) url(\"https://secure.aadcdn.microsoftonline-p.com/ests/2.1.6999.16/content/images//backgrounds/0.jp" ascii
    $s12 = "Constants.DEFAULT_LOGO_ALT = 'Hang on a moment while we sign you out.';" fullword ascii
    $s13 = "document.cookie = \"SOS\" + \"=1; path=/\";" fullword ascii
    $s14 = "signoutStatusMessage.text(\"You may still be signed in to some applications. Close your browser to finish signing out.\");" fullword ascii
    $s15 = "<script type=\"text/javascript\" id=\"SCRIPT_2\">function SetImageStatus(imageIndex, status)" fullword ascii
    $s16 = "<script type=\"text/javascript\" id=\"SCRIPT_18\">$Do.when(\"doc.ready\", function ()" fullword ascii
    $s17 = "<script type=\"text/javascript\" id=\"SCRIPT_3\">var imageStatusArray = new Array(0);" fullword ascii
    $s18 = "Constants.DEFAULT_BOILERPLATE_HEADER = '';" fullword ascii
    $s19 = "signoutStatusMessage.text(\"It\\u0027s a good idea to close all browser windows.\");" fullword ascii
    $s20 = "Constants.BOILERPLATE_HEADER = '';" fullword ascii

  condition:
    (uint16(0) == 0x733c and
      filesize < 60KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}