rule dotnet_binary_file
{
    meta:
        author = "CYB3RMX"
        description = "Detects possible .NET binary files."
    strings:
        $dot1 = "mscoree.dll" wide ascii
        $dot2 = "_CorExeMain" wide ascii
        $dot3 = "_CorDllMain" wide ascii
        $dot4 = "mscorlib" wide ascii
        $dot5 = ".NETFramework" wide ascii
    condition:
        ((2 of ($dot*)) or (all of ($dot*)))
}