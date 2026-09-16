rule TTP_XOR_QUAD_CurrentVersionRun_443d {
  strings:
    $key_443d = { 17 52 [2] 33 5c [2] 18 70 [2] 36 52 [2] 22 49 [2] 2d 53 [2] 33 4e [2] 31 4f [2] 2a 49 [2] 36 4e [2] 2a 61 }

  condition:
    any of them
}