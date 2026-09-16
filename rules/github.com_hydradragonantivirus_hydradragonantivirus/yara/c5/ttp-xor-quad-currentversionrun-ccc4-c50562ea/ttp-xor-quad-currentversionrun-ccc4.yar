rule TTP_XOR_QUAD_CurrentVersionRun_ccc4 {
  strings:
    $key_ccc4 = { 9f ab [2] bb a5 [2] 90 89 [2] be ab [2] aa b0 [2] a5 aa [2] bb b7 [2] b9 b6 [2] a2 b0 [2] be b7 [2] a2 98 }

  condition:
    any of them
}