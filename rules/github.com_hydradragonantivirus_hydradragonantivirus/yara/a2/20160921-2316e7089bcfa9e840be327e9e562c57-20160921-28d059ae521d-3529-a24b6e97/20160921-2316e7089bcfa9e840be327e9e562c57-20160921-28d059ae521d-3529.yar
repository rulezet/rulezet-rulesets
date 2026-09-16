rule _20160921_2316e7089bcfa9e840be327e9e562c57_20160921_28d059ae521d_3529 {
  meta:
    description = "datamaliciousorder - from files 20160921_2316e7089bcfa9e840be327e9e562c57.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160921_f232e0ba2dbd66b232f717e912f70cd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11216ce48a9d383f0d3cab03de05ba1550ae25c7b5d18a758666cfdd75159fe2"
    hash2       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash3       = "d8231c7ebf650f58f63f7ed6d3017e0ee9895c1dd821750dcc6c78003fc81b2b"

  strings:
    $s1 = "nction f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s2 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s3 = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"PTs" ascii
    $s4 = "function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s5 = "n f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s6 = "(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}