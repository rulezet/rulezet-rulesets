rule TTP_XOR_WriteProcessMemory_8abf {
  strings:
    $key_8abf = { dd cd [2] ef ef [2] e9 da [2] c7 da [2] f8 c6 }

  condition:
    any of them
}