rule embedded_exe 
{
    meta:
    description = "Detects embedded executables"
    
    strings:
    $a = "This program cannot be run in DOS mode"
    
    condition:
    $a in (1024..filesize)
}