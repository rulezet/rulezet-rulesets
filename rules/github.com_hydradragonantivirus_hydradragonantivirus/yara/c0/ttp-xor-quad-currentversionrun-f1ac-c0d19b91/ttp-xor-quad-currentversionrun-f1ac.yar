rule TTP_XOR_QUAD_CurrentVersionRun_f1ac {
  strings:
    $key_f1ac = { a2 c3 [2] 86 cd [2] ad e1 [2] 83 c3 [2] 97 d8 [2] 98 c2 [2] 86 df [2] 84 de [2] 9f d8 [2] 83 df [2] 9f f0 }

  condition:
    any of them
}