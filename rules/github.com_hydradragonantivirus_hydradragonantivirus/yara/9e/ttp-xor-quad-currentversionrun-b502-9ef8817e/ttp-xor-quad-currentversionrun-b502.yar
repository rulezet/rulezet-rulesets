rule TTP_XOR_QUAD_CurrentVersionRun_b502 {
  strings:
    $key_b502 = { e6 6d [2] c2 63 [2] e9 4f [2] c7 6d [2] d3 76 [2] dc 6c [2] c2 71 [2] c0 70 [2] db 76 [2] c7 71 [2] db 5e }

  condition:
    any of them
}