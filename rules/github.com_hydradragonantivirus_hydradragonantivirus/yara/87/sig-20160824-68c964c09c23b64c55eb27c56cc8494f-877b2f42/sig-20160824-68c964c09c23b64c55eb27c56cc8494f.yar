rule sig_20160824_68c964c09c23b64c55eb27c56cc8494f {
  meta:
    description = "datamaliciousorder - file 20160824_68c964c09c23b64c55eb27c56cc8494f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5ca4e367b05dd391a7c66c04b30c629a03fda9b38f25f5971de83e28a8419b"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}