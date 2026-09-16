rule TTP_XOR_QUAD_CurrentVersionRun_c48d {
  strings:
    $key_c48d = { 97 e2 [2] b3 ec [2] 98 c0 [2] b6 e2 [2] a2 f9 [2] ad e3 [2] b3 fe [2] b1 ff [2] aa f9 [2] b6 fe [2] aa d1 }

  condition:
    any of them
}