rule _20160915_14b427a7401efd15ad40ab38a0ff0849_20160915_1ab5eea58d67_734 {
  meta:
    description = "datamaliciousorder - from files 20160915_14b427a7401efd15ad40ab38a0ff0849.js, 20160915_1ab5eea58d67b59b8bf85a14e127cae9.js, 20160915_25453e40d36267aa653c39884dbaf029.js, 20160915_2f9a6bb32c1e3adca1ab551eae40ddc6.js, 20160915_43d1b5992960a365931311fc1ededd9e.js, 20160915_542ee961b0e8a41e992c0e6a8e5d6061.js, 20160915_6ff02bf870ac99f6b1afa3cdb3fb1ca4.js, 20160915_7174a51df35cc59b7d2bec8d9d14fdc4.js, 20160915_75eaa017630ada44eed2960813493f35.js, 20160915_82945f93a0a43f057cfdebd36db0242d.js, 20160915_8d5a66377fb7a4d35283060de78a4825.js, 20160915_a073be0ac0bd8d151062f5b26271851d.js, 20160915_a27a7b49ee8c19c13cb1a1825e629ed3.js, 20160915_ac595b9c92361ccb910c06f40971de33.js, 20160915_d53bbc3a7c2dc3f587e616aeba0625d4.js, 20160915_d654a7fe77fd0165161393adff1c29bb.js, 20160915_eef47bf6f9e4747a9b288f146cc9b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a589a0cb92cd37d606bbf0396a3f1edd1268e6af22dc257c0fd2c685018f5193"
    hash2       = "6f48af0b2f44c23dd12e958573c329734c2d5756fa942cde94d8524ebc19a68b"
    hash3       = "741bd6fc6bd5ab5222d3d016b062c090bdfb056460459e286222964b408d9134"
    hash4       = "fbc1c63aa90704b1c6751004031b52ef9f2e060fabe4f93760aeb2cadfc007c6"
    hash5       = "3d28a083eeb650100b143340e94a574772dcd9cb0a4972e83028257b9db05116"
    hash6       = "87c4fed5a397906e3a4b4d998e177a50ed9f03fc9e0b3d9c3e3bb9bc78d2e1ff"
    hash7       = "198636334e30cca2d147e4d078faeea68d75d276c38d454766d7fa14fd6f9a9b"
    hash8       = "c423cde4d1486701ce7095e547eabb661d18c4535a298b141a6d8a3ea1e7a17f"
    hash9       = "415aa6e4929b32fb215a63a4fe03b5f21f72edd7468b97770f66f63053d67523"
    hash10      = "f1fb6032ef49bd4fc2871e0a55cb70ae24f8054f28b75af8ded08609501942f1"
    hash11      = "e21547242d74d3f9d692789d171210ee5004abaf7f30235ca02ef9a3f5880c80"
    hash12      = "b0f8735adbcdd9eba85b907b19756b8f8c984fe7f37b504d040e0a638f58c774"
    hash13      = "5a422b5a01e7266115bd0beb1b1e223f243668264f3a837a2cc537c5094241e7"
    hash14      = "4e382e32cf76ba2b7fb3b65366b603932f9e0ff99fa8434e371ae9bd750b9f1f"
    hash15      = "09fef863703972032c264243ffb9f1937f01f2455a80282bff04060c88ac34fb"
    hash16      = "ad80561afa7c481d599d4c16fa12f8c2b4f820694ccf99d005c8b75740bc18b6"
    hash17      = "7b6695c80d2a90b876edcb6c6bb2908c62196464b9ab5c85407deb3ea63d27eb"

  strings:
    $s1 = "\";})()], \"MLz\": [3, (function f(){return \"\\x7a\";})()], \"St\": [3, (function f(){return \"\\x7c\";})()], \"Kr\": [3, (func" ascii
    $s2 = "rn \"\\x43\";})()], \"VMm\": [3, (function f(){return \"\\x48\";})()], \"Jp0\": [3, (function f(){return \"\\x49\";})()], \"CEb" ascii
    $s3 = ";})()], \"GXa\": [3, (function f(){return \"\\x41\";})()], \"Dn\": [3, (function f(){return \"\\x42\";})()], \"SHk\": [3, (funct" ascii
    $s4 = "\"Vx\": [3, (function f(){return \"0\";})()], \"Of\": [3, (function f(){return \"4\";})()], \"Fa\": [3, (function f(){return \"" ascii
    $s5 = "\"\\x4e\";})()], \"Jp\": [3, (function f(){return \"\\x4f\";})()], \"Ha\": [3, (function f(){return \"2\";})()], \"Hn\": [3, (fu" ascii
    $s6 = "[3, (function f(){return \"8\";})()], \"EEn\": [3, (function f(){return \"\\x44\";})()], \"Zy\": [3, (function f(){return \"\\x4" ascii
    $s7 = "var COt = {\"QQd\": [3, (function f(){return \"\\x6b\";})()], \"FTe\": [3, (function f(){return \"\\x79\";})()], \"Hh\": [3, (fu" ascii

  condition:
    (uint16(0) == 0x0a0a and (all of them)
    ) or (all of them)
}