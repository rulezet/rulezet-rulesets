rule sig_20160301_a6979954909c7dfe140176cc29ca12cd {
  meta:
    description = "datamaliciousorder - file 20160301_a6979954909c7dfe140176cc29ca12cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c5759d570f298b373c19bbb94b4ff0f12de337efb44bf671e07b37aefe778fb"

  strings:
    $s1 = "centralGram = collectivePlus[(\"administration\", \"collector\", \"ExpandEnvironmentStrings\")]((\"hall\", \"autonomy\", \"%TEMP" ascii
    $s2 = "centralGram = collectivePlus[(\"administration\", \"collector\", \"ExpandEnvironmentStrings\")]((\"hall\", \"autonomy\", \"%TEMP" ascii
    $s3 = "while (approximationCampaign[(\"camera\", \"position\", \"command\", \"readystate\")] < (((((([+!+[]])) + \"\" + (([!+[] + !+[]]" ascii
    $s4 = "angelMotor = (((Math.pow(482, 2) - 231491) / (0 | 17)), this);" fullword ascii
    $s5 = "while (approximationCampaign[(\"camera\", \"position\", \"command\", \"readystate\")] < (((((([+!+[]])) + \"\" + (([!+[] + !+[]]" ascii
    $s6 = "postscriptIntegral[(\"synonym\", \"write\")](approximationCampaign[(\"sport\", function String.prototype.subjectiveBarge() {" fullword ascii
    $s7 = "} catch (dustRank) {};" fullword ascii

  condition:
    uint16(0) == 0x6e61 and
    all of them
}