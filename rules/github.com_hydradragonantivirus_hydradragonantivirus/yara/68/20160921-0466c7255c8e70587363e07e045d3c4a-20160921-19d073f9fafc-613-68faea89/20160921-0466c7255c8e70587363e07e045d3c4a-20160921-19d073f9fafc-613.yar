rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_19d073f9fafc_613 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash3       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash4       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash5       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash6       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash7       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash8       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash9       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash10      = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash11      = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash12      = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash13      = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash14      = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash15      = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash16      = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash17      = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash18      = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash19      = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash20      = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash21      = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash22      = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash23      = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash24      = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"
    hash25      = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = ")(),(function f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Kw\";})(),(function f000" ascii
    $s2  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f00" ascii
    $s3  = "\"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s4  = "urn \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s5  = "0(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\"" ascii
    $s6  = "return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s7  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s8  = "rn \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s9  = "unction f000(){return \"Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){retu" ascii
    $s10 = "turn \"Sv\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s11 = "n\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function " ascii
    $s12 = "urn \"KIc\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s13 = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qz" ascii
    $s14 = "00(){return \"Vu\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\"" ascii
    $s15 = " f000(){return \"Uo\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"TKl" ascii
    $s16 = "\"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s17 = ";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii
    $s18 = "unction f000(){return \"Oh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";})(),(function f000(){ret" ascii
    $s19 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"IAa\";})(),(function f" ascii
    $s20 = "rn \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}