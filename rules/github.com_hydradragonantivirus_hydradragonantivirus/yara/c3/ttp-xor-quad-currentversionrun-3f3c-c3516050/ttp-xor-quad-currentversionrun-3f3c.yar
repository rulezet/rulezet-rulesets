rule TTP_XOR_QUAD_CurrentVersionRun_3f3c {
  strings:
    $key_3f3c = { 6c 53 [2] 48 5d [2] 63 71 [2] 4d 53 [2] 59 48 [2] 56 52 [2] 48 4f [2] 4a 4e [2] 51 48 [2] 4d 4f [2] 51 60 }

  condition:
    any of them
}