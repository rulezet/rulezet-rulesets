rule _20160520_175783cbb336f5089aea7a7eabf64d37_20160520_1c4fee3c95cb_2178 {
  meta:
    description = "datamaliciousorder - from files 20160520_175783cbb336f5089aea7a7eabf64d37.js, 20160520_1c4fee3c95cb5c3e963ad975a4303863.js, 20160520_2e75637975e52fe5b81310b7f2cef4c4.js, 20160520_6d5a9d2090c2c5199b0f35a12a24dd7e.js, 20160520_b97dba49de7b4c843c1d27fd6d752ec0.js, 20160520_e6a499fdef8890faa5a00c935aa3cb76.js, 20160520_f20de04906349271e167af5f5a0251ef.js, 20160520_ffcfe53f11d4a2c4795cc6ab362550e2.js, 20160523_32dd9dd05e57c213bfe7d9b0d1a5b243.js, 20160523_53a2936b85223dd2395e2f50d1b13b50.js, 20160523_f44485dfa63babf6a56cb51758648df7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc87ab0b315964c2381727b441232d2425f981a168769c34ff0ea2ae250b25b9"
    hash2       = "c2ebb786f68a01aa7681772bd0abde04372e4e0d815bb89db8e359bd5fa23496"
    hash3       = "7d124a1273cd9a3f5cf66648689fc57028bbf5788712956b6b745b38f3c3cb66"
    hash4       = "92738cdc66e1b6b9d73bbcbf31b8003743620cbd4c618552b82318dc9a5a581f"
    hash5       = "1306a895c12ed250a2bfd1c727d5916ab2ba84419ff170ae926067e8c7011c8d"
    hash6       = "642b47a2716c207643102441f37767b075b390600205491326b991c200773efd"
    hash7       = "89ce7572df9a445b8b61d0a61ab19053585db1779ccf7fae55f3b6da7dfa4a86"
    hash8       = "6ee00ca7f2812d87bf61da7a78bc17cef10cd861e4f141359016088f04b18730"
    hash9       = "7b792c3bd22a5ed87a9aab45e98b6c189c884fbcb6a70364ec84bd0ce1156a3c"
    hash10      = "8221c0e2b7fd82fafd1107dc9d98bdf11089e7d85d0660320e9e579c2f9836f2"
    hash11      = "7dc8f71268c17957cfe6a35a196af0acc99ac56e899b39da5a8be5506d70d9a9"

  strings:
    $s1 = "Point.dot = function(p1, p2) {" fullword ascii
    $s2 = "Point.cross = function(p1, p2) {" fullword ascii
    $s3 = "Point.distance = function(p1, p2) {" fullword ascii
    $s4 = "    return p1.x * p2.y - p1.y * p2.x;" fullword ascii
    $s5 = "    return Math.sqrt(a * a + b * b);" fullword ascii
    $s6 = "    return p1.x * p2.x + p1.y * p2.y;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}