rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_72cf8bebbcf4_268 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash3       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash4       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1  = "\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f" ascii
    $s2  = "urn \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3  = "f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"W" ascii
    $s4  = "n \"Br\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s5  = "MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s6  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"H" ascii
    $s7  = "ction f000(){return \"Vj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return " ascii
    $s8  = "})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s9  = "(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Br\";}" ascii
    $s10 = "function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s11 = " f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"" ascii
    $s12 = ")(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(" ascii
    $s13 = "ion f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s14 = "n f000(){return \"Wy\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Uo" ascii
    $s15 = "{return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"KXg\";}" ascii
    $s16 = "00(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s17 = "){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})" ascii
    $s18 = "rn \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s19 = " f000(){return \"Lp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WI" ascii
    $s20 = "{return \"Br\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}