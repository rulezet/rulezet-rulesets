import "dotnet"
rule SUSP_DotNet_Method_Param_HTTP
{
    meta:
        author = "Greg Lesnewich"
        date = "2023-01-06"
        version = "1.0"
        DaysofYARA = "6/100"


    condition:
    for any item in dotnet.classes: (
        for any methy in item.methods: (
            for any param in methy.parameters: (
                param.name icontains "http"
            )
        )
    )

}