rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_18eedffe02de_3221 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash3       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash4       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash5       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash6       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash7       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash8       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash9       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"
    hash10      = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash11      = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash12      = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"
    hash13      = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = "ion fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"" ascii
    $s2 = "eturn \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"ZVi\";})(" ascii
    $s3 = ";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf\";})(),(function fu" ascii
    $s4 = "(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck()" ascii
    $s5 = "n \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s6 = "k(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}