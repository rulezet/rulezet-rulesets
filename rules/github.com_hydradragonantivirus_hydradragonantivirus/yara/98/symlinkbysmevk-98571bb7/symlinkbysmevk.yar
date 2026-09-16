rule SymlinkbySmevk {
  meta:
    description = "case109 - file SymlinkbySmevk.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "198f3f0b76210f9901762e94b525d93fc3c66178d1373c13b2994391c0159729"

  strings:
    $s1  = "@symlink('/home2/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
    $s2  = "@symlink('/home3/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
    $s3  = "@symlink('/home4/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
    $s4  = "@symlink('/home/' . $user . '/public_html/supports/includes/iso4217.php', $user . '-hostbills-supports.txt');" fullword ascii
    $s5  = "@symlink('/home/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
    $s6  = "@symlink('/home2/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
    $s7  = "@symlink('/home3/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
    $s8  = "@symlink('/home4/' . $user . '/public_html/support/includes/iso4217.php', $user . '-hostbills-support.txt');" fullword ascii
    $s9  = "@symlink('/home3/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
    $s10 = "@symlink('/home2/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
    $s11 = "@symlink('/home3/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
    $s12 = "@symlink('/home4/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
    $s13 = "@symlink('/home2/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
    $s14 = "@symlink('/home4/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
    $s15 = "@symlink('/home/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
    $s16 = "@symlink('/home/' . $user . '/public_html/hosting/configuration.php', $user . '-hosting-WHMCS.txt');" fullword ascii
    $s17 = "@symlink('/home/' . $user . '/public_html/clientsupport/configuration.php', $user . '-clientsupport-WHMCS.txt');" fullword ascii
    $s18 = "@symlink('/home4/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
    $s19 = "@symlink('/home2/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii
    $s20 = "@symlink('/home3/' . $user . '/public_html/hosts/configuration.php', $user . '-hosts-WHMCS.txt');" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 200KB and
      (8 of them)
    ) or (all of them)
}