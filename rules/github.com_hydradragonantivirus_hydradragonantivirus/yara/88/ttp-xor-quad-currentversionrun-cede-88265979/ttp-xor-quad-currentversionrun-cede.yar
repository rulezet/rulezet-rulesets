rule TTP_XOR_QUAD_CurrentVersionRun_cede {
  strings:
    $key_cede = { 9d b1 [2] b9 bf [2] 92 93 [2] bc b1 [2] a8 aa [2] a7 b0 [2] b9 ad [2] bb ac [2] a0 aa [2] bc ad [2] a0 82 }

  condition:
    any of them
}