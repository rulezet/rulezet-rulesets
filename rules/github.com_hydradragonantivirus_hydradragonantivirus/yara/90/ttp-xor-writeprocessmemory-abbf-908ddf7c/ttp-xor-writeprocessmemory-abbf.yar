rule TTP_XOR_WriteProcessMemory_abbf {
  strings:
    $key_abbf = { fc cd [2] ce ef [2] c8 da [2] e6 da [2] d9 c6 }

  condition:
    any of them
}