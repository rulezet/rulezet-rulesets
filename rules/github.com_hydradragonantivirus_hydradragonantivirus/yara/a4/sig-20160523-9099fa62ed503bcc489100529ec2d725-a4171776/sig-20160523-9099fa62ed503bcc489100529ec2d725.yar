rule sig_20160523_9099fa62ed503bcc489100529ec2d725 {
  meta:
    description = "datamaliciousorder - file 20160523_9099fa62ed503bcc489100529ec2d725.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86c4ebddffadeeaef314496b460ffbb200a52a3953ca70e2240d77bdbf5a9551"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}