rule TTP_XOR_QUAD_CurrentVersionRun_c393 {
  strings:
    $key_c393 = { 90 fc [2] b4 f2 [2] 9f de [2] b1 fc [2] a5 e7 [2] aa fd [2] b4 e0 [2] b6 e1 [2] ad e7 [2] b1 e0 [2] ad cf }

  condition:
    any of them
}