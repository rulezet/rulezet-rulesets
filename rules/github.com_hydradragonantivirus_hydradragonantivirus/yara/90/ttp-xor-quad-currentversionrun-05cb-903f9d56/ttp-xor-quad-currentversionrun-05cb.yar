rule TTP_XOR_QUAD_CurrentVersionRun_05cb {
  strings:
    $key_05cb = { 56 a4 [2] 72 aa [2] 59 86 [2] 77 a4 [2] 63 bf [2] 6c a5 [2] 72 b8 [2] 70 b9 [2] 6b bf [2] 77 b8 [2] 6b 97 }

  condition:
    any of them
}