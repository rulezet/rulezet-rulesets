rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_71668d4dffd1_3039 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash3       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash4       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash5       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash6       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash7       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash8       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash9       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash10      = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash11      = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash12      = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "00(){return \"Mt\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "n f000(){return \"BMj\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"" ascii
    $s3 = ",(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s4 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nv\";})" ascii
    $s5 = "{return \"DAp\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})" ascii
    $s6 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s7 = "(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}