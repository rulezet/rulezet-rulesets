rule TTP_XOR_QUAD_CurrentVersionRun_433c {
  strings:
    $key_433c = { 10 53 [2] 34 5d [2] 1f 71 [2] 31 53 [2] 25 48 [2] 2a 52 [2] 34 4f [2] 36 4e [2] 2d 48 [2] 31 4f [2] 2d 60 }

  condition:
    any of them
}