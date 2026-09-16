rule TTP_XOR_QUAD_CurrentVersionRun_efd9 {
  strings:
    $key_efd9 = { bc b6 [2] 98 b8 [2] b3 94 [2] 9d b6 [2] 89 ad [2] 86 b7 [2] 98 aa [2] 9a ab [2] 81 ad [2] 9d aa [2] 81 85 }

  condition:
    any of them
}