rule TTP_XOR_QUAD_CurrentVersionRun_623c {
  strings:
    $key_623c = { 31 53 [2] 15 5d [2] 3e 71 [2] 10 53 [2] 04 48 [2] 0b 52 [2] 15 4f [2] 17 4e [2] 0c 48 [2] 10 4f [2] 0c 60 }

  condition:
    any of them
}