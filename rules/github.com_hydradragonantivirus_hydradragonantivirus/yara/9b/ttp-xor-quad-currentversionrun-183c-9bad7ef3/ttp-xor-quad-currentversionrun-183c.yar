rule TTP_XOR_QUAD_CurrentVersionRun_183c {
  strings:
    $key_183c = { 4b 53 [2] 6f 5d [2] 44 71 [2] 6a 53 [2] 7e 48 [2] 71 52 [2] 6f 4f [2] 6d 4e [2] 76 48 [2] 6a 4f [2] 76 60 }

  condition:
    any of them
}