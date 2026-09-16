rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_4550 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash4       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash5       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash6       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"

  strings:
    $s1 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})" ascii
    $s2 = "ck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz" ascii
    $s3 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx\";})()" ascii
    $s4 = "RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s5 = "SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}