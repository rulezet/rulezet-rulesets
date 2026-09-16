rule finspy_macos_installer {
  meta:
    description = "Rule for FinSpy OSX installer"
    author      = "Etienne Maynier, Amnesty Tech"

  strings:
    $s1 = "80.bundle.zip" ascii
    $s2 = "AAC.dat" ascii
    $s3 = "arch.zip" ascii
    $s4 = "/Library/LaunchAgents" ascii
    $s5 = "7FC.dat" ascii
    $s6 = "logind.plist" ascii
    $s7 = "org.logind.ctp.archive" ascii
    $s8 = "helper" ascii
    $s9 = "Contents/Resources/7f.bundle/Contents/Resources" ascii

  condition:
    uint16(0) == 0xFACF and 8 of them
}