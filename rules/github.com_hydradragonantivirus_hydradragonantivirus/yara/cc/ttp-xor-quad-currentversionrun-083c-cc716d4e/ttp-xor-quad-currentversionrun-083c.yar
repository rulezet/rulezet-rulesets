rule TTP_XOR_QUAD_CurrentVersionRun_083c {
  strings:
    $key_083c = { 5b 53 [2] 7f 5d [2] 54 71 [2] 7a 53 [2] 6e 48 [2] 61 52 [2] 7f 4f [2] 7d 4e [2] 66 48 [2] 7a 4f [2] 66 60 }

  condition:
    any of them
}