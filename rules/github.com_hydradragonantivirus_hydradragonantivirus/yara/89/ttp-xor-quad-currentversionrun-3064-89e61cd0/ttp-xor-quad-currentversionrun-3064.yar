rule TTP_XOR_QUAD_CurrentVersionRun_3064 {
  strings:
    $key_3064 = { 63 0b [2] 47 05 [2] 6c 29 [2] 42 0b [2] 56 10 [2] 59 0a [2] 47 17 [2] 45 16 [2] 5e 10 [2] 42 17 [2] 5e 38 }

  condition:
    any of them
}