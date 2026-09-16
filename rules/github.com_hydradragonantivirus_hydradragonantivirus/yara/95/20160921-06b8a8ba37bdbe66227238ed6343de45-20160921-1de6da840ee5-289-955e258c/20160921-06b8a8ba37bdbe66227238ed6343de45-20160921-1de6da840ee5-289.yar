rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_1de6da840ee5_289 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js, 20160922_41319625a3342333693d5eefb82a43ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash3       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash4       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash5       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash6       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash7       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash8       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash9       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash10      = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash11      = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash12      = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"
    hash13      = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"

  strings:
    $s1  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return" ascii
    $s2  = "eturn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"UEg\";})()" ascii
    $s3  = "GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(functio" ascii
    $s4  = "unction f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s5  = ";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s6  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MOc\";})(),(function f000(){return " ascii
    $s7  = "turn \"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s8  = "n \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s9  = "turn \"IPu\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s10 = "){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"HJm\";})" ascii
    $s11 = "eturn \"Wy\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s12 = "ction f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s13 = " f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Ml" ascii
    $s14 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(functio" ascii
    $s15 = "000(){return \"Mt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s16 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s17 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZFe\";})(),(function" ascii
    $s18 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Y" ascii
    $s19 = ",(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s20 = "),(function f000(){return \"ZIi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}