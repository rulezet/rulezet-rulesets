rule TTP_XOR_QUAD_CurrentVersionRun_e6c5 {
  strings:
    $key_e6c5 = { b5 aa [2] 91 a4 [2] ba 88 [2] 94 aa [2] 80 b1 [2] 8f ab [2] 91 b6 [2] 93 b7 [2] 88 b1 [2] 94 b6 [2] 88 99 }

  condition:
    any of them
}