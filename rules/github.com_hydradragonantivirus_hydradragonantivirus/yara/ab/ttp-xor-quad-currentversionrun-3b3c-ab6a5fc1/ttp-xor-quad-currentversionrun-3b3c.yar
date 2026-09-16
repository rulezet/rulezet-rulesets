rule TTP_XOR_QUAD_CurrentVersionRun_3b3c {
  strings:
    $key_3b3c = { 68 53 [2] 4c 5d [2] 67 71 [2] 49 53 [2] 5d 48 [2] 52 52 [2] 4c 4f [2] 4e 4e [2] 55 48 [2] 49 4f [2] 55 60 }

  condition:
    any of them
}