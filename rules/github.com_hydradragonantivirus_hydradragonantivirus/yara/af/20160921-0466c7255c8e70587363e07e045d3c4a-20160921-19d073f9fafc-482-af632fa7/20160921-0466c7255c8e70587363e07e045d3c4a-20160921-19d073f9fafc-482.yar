rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_19d073f9fafc_482 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash3       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash4       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash5       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash6       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash7       = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash8       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash9       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash10      = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash11      = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash12      = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash13      = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash14      = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash15      = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash16      = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um" ascii
    $s2  = "(function f000(){return \"Wb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3  = " f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s4  = "ction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s5  = "unction f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s6  = "return \"Mc\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7  = "{return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";}" ascii
    $s8  = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";}" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s10 = "tion f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s11 = " f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"O" ascii
    $s12 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})" ascii
    $s13 = "(){return \"Br\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})" ascii
    $s14 = "turn \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s15 = "n \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s16 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s17 = "0(){return \"Um\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s18 = "{return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s19 = "})(),(function f000(){return \"DYs\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s20 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}