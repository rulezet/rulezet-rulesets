rule _20160921_24a000738e40009c8bea0a81a0c09cf4_20160921_64f93de6a09e_995 {
  meta:
    description = "datamaliciousorder - from files 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash2       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash3       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash4       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash5       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash6       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash7       = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash8       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash9       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash10      = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = "turn \"ZGq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s2  = "tion f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MOc\";})(),(function f000(){return" ascii
    $s3  = "n\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s4  = "n \"Mt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5  = ",(function f000(){return \"Oh\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){r" ascii
    $s6  = "n f000(){return \"ZFe\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s7  = "on f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s8  = "\"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s9  = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";" ascii
    $s10 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"HJm\";})(),(functio" ascii
    $s11 = "(function f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){" ascii
    $s12 = "nction f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s13 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NYh\";})(),(function f00" ascii
    $s14 = "{return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})" ascii
    $s15 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s16 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nx\";})(),(f" ascii
    $s17 = "Na\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s18 = "eturn \"PTi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})()," ascii
    $s19 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}