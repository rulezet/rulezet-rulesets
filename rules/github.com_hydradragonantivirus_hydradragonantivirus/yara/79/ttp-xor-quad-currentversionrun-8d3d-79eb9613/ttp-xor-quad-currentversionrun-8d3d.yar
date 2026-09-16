rule TTP_XOR_QUAD_CurrentVersionRun_8d3d {
  strings:
    $key_8d3d = { de 52 [2] fa 5c [2] d1 70 [2] ff 52 [2] eb 49 [2] e4 53 [2] fa 4e [2] f8 4f [2] e3 49 [2] ff 4e [2] e3 61 }

  condition:
    any of them
}