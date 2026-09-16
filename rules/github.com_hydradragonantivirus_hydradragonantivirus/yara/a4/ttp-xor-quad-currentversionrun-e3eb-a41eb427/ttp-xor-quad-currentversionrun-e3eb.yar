rule TTP_XOR_QUAD_CurrentVersionRun_e3eb {
  strings:
    $key_e3eb = { b0 84 [2] 94 8a [2] bf a6 [2] 91 84 [2] 85 9f [2] 8a 85 [2] 94 98 [2] 96 99 [2] 8d 9f [2] 91 98 [2] 8d b7 }

  condition:
    any of them
}