rule TTP_XOR_QUAD_CurrentVersionRun_8501 {
  strings:
    $key_8501 = { d6 6e [2] f2 60 [2] d9 4c [2] f7 6e [2] e3 75 [2] ec 6f [2] f2 72 [2] f0 73 [2] eb 75 [2] f7 72 [2] eb 5d }

  condition:
    any of them
}