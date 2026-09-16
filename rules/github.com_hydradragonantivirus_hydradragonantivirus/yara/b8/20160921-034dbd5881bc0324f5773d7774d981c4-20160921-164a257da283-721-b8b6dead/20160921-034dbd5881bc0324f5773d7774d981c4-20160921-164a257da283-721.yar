rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_164a257da283_721 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_164a257da283d5c859dcaffb21bf752c.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_3b7ec37cdbfac434e32c8743c60228af.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_56567a449e5ae44cd4a4e62bb55e63f3.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_a0b892850e7511a70b7c95d4603de0d8.js, 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js, 20160921_f2abfe62ed227fb547869419a6d3af3c.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js, 20160921_fb2ccc1a635114bc23ea8a0a8413b110.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "36edb416a5f8703ead3fb8f8fbb7a0fb98ac21c559eb20558b33460ba9dfc9a0"
    hash3       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash4       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash5       = "86390741cf6e610c2e526db749631548b514c268decade5a5870edfebb141d4b"
    hash6       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash7       = "e0950a0ccf96b116ed17c3fbaa99325e34f0b717e3e354bd1f926eee8465c6a7"
    hash8       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash9       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash10      = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash11      = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash12      = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash13      = "0b5459eb728a278a131a764184d1d333fcd3fc212087b66d9cedce792b1a2d7a"
    hash14      = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash15      = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"
    hash16      = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"
    hash17      = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"
    hash18      = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"
    hash19      = "c85e7d8e5c1682f21f2d8c9a0e1f6039d583d7eda8276ca9ed3ed381fbde9a7e"
    hash20      = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1  = "ck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YAv" ascii
    $s2  = "ion fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "Pu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s4  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"G" ascii
    $s5  = "n \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(funct" ascii
    $s6  = "turn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(" ascii
    $s7  = "f\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Vf\";})(),(function " ascii
    $s8  = "(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){r" ascii
    $s9  = "fuck(){return \"Ve\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s10 = "return \"Yk\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s11 = "ion fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s12 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Wo0" ascii
    $s13 = ";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s14 = "turn \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s15 = "\"Xw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(functi" ascii
    $s16 = "(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s17 = "ion fuck(){return \"IOs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s18 = "unction fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){re" ascii
    $s19 = " \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s20 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}