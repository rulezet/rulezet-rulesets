rule TTP_XOR_QUAD_CurrentVersionRun_443f {
  strings:
    $key_443f = { 17 50 [2] 33 5e [2] 18 72 [2] 36 50 [2] 22 4b [2] 2d 51 [2] 33 4c [2] 31 4d [2] 2a 4b [2] 36 4c [2] 2a 63 }

  condition:
    any of them
}