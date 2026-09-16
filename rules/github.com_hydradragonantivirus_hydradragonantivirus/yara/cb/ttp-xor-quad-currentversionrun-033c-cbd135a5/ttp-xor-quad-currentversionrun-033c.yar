rule TTP_XOR_QUAD_CurrentVersionRun_033c {
  strings:
    $key_033c = { 50 53 [2] 74 5d [2] 5f 71 [2] 71 53 [2] 65 48 [2] 6a 52 [2] 74 4f [2] 76 4e [2] 6d 48 [2] 71 4f [2] 6d 60 }

  condition:
    any of them
}