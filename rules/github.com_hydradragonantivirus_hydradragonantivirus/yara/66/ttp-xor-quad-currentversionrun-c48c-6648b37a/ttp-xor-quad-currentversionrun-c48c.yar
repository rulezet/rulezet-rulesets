rule TTP_XOR_QUAD_CurrentVersionRun_c48c {
  strings:
    $key_c48c = { 97 e3 [2] b3 ed [2] 98 c1 [2] b6 e3 [2] a2 f8 [2] ad e2 [2] b3 ff [2] b1 fe [2] aa f8 [2] b6 ff [2] aa d0 }

  condition:
    any of them
}