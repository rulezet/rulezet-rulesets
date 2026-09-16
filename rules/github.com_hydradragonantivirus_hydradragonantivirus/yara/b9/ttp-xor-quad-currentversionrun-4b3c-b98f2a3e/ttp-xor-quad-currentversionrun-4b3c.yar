rule TTP_XOR_QUAD_CurrentVersionRun_4b3c {
  strings:
    $key_4b3c = { 18 53 [2] 3c 5d [2] 17 71 [2] 39 53 [2] 2d 48 [2] 22 52 [2] 3c 4f [2] 3e 4e [2] 25 48 [2] 39 4f [2] 25 60 }

  condition:
    any of them
}