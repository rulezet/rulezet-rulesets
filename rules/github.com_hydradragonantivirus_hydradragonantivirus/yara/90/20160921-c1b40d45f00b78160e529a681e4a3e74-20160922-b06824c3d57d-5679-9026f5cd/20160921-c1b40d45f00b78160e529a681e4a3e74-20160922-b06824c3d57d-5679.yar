rule _20160921_c1b40d45f00b78160e529a681e4a3e74_20160922_b06824c3d57d_5679 {
  meta:
    description = "datamaliciousorder - from files 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash2       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash3       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s2 = "{return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s3 = "nction f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){retu" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retur" ascii
    $s5 = "{return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}