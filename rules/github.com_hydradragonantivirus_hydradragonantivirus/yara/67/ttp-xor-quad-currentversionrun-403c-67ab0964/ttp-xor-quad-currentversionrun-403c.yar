rule TTP_XOR_QUAD_CurrentVersionRun_403c {
  strings:
    $key_403c = { 13 53 [2] 37 5d [2] 1c 71 [2] 32 53 [2] 26 48 [2] 29 52 [2] 37 4f [2] 35 4e [2] 2e 48 [2] 32 4f [2] 2e 60 }

  condition:
    any of them
}