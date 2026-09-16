rule sig_20160525_268751acab22594a0e34b6fa03bd719f {
  meta:
    description = "datamaliciousorder - file 20160525_268751acab22594a0e34b6fa03bd719f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57b82eb0b93cfb9a0e5b987b3557d17e1ed85df2fa7fcadc4d13864a43dd6d01"

  strings:
    $s1 = "neti + deerdi[rerednera[rerednera = /*  WVB VVl OcZ */ sdnet rav" fullword ascii
    $s2 = "rape rav\\n;\"f2x\\\\f2x\\\\:\" = dnenoisilloce rav\\n;\"faec6x\\\\\" = me rav;};keppele nruter{)keppele(gedotdare noitcnuf\\n;" ascii
    $s3 = ";\"tgnec6x\\\\\" = gsmw rav\\n;)1(]\"tA\"+\"27x\\\\\"+\"\"+\"16x\\\\\"+\"hc\"[eixodw = suidarelcitrapw rav;\"7h0\" = eixodw rav'" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}