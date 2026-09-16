rule sig_20160525_6db584a3e46b6c36c96b75270e12dd56 {
  meta:
    description = "datamaliciousorder - file 20160525_6db584a3e46b6c36c96b75270e12dd56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdfb051a67006493cac2d856a74264e3bc4183773879c169d7653ccad5eda7f7"

  strings:
    $s1 = "+ sdnetv[eixodb    \\n;)(]gsml[eixodb    \\n         ;mb = ]rerednerp + cthp[eixodb    \\n;tsilslianbmuhtoa = ]dnenoisillocn + s" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}