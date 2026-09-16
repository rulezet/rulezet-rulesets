rule TTP_XOR_WriteProcessMemory_ada8 {
  strings:
    $key_ada8 = { fa da [2] c8 f8 [2] ce cd [2] e0 cd [2] df d1 }

  condition:
    any of them
}