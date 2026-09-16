rule TTP_XOR_QUAD_CurrentVersionRun_6a3c {
  strings:
    $key_6a3c = { 39 53 [2] 1d 5d [2] 36 71 [2] 18 53 [2] 0c 48 [2] 03 52 [2] 1d 4f [2] 1f 4e [2] 04 48 [2] 18 4f [2] 04 60 }

  condition:
    any of them
}