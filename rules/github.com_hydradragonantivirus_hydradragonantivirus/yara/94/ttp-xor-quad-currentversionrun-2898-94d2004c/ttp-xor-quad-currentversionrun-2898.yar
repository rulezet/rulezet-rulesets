rule TTP_XOR_QUAD_CurrentVersionRun_2898 {
  strings:
    $key_2898 = { 7b f7 [2] 5f f9 [2] 74 d5 [2] 5a f7 [2] 4e ec [2] 41 f6 [2] 5f eb [2] 5d ea [2] 46 ec [2] 5a eb [2] 46 c4 }

  condition:
    any of them
}